#!/usr/bin/env python3
"""Qualify the offline artifact image against an actual local Action measurement.

Rootless Podman only: cached immutable base, no pull/network, read-only source,
no capabilities, bounded CPU/RAM/PIDs/tmp, and only a new report directory writable.
This does not publish an image or qualify the distinct networked source rebuild.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

from action_acquire import digest_value, extract_package, verified_snapshot
from action_local_smoke import ROOT, SCENARIOS, run, write_json
from action_run import child_environment, require, validate


def identifier(text):
    value = text.strip().removeprefix("sha256:")
    require(re.fullmatch(r"[0-9a-f]{64}", value) is not None, "expected exact local image/container ID")
    return value


def bind_path(path):
    value = str(path.resolve(strict=True))
    require(not any(char in value for char in (",", ":", "\n", "\r")), "unsupported bind path delimiter")
    return value


def validate_runtime(container, image, fixture_root, output):
    require(identifier(container["Image"]) == identifier(image), "runtime image identity mismatch")
    host = container["HostConfig"]
    require(host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True, "network/rootfs isolation missing")
    require(not host["Privileged"] and not host["CapAdd"], "unexpected elevated runtime privilege")
    require(host["Memory"] == 6 * 1024**3 and host["MemorySwap"] == 12 * 1024**3
            and host["PidsLimit"] == 256 and host["CpuPeriod"] > 0
            and host["CpuQuota"] == 2 * host["CpuPeriod"], "runtime resource limits differ")
    require({"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
             "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP",
             "CAP_SETUID", "CAP_SYS_CHROOT"} <= set(host["CapDrop"]), "runtime capabilities not dropped")
    require({"no-new-privileges", "label=disable"} <= set(host["SecurityOpt"]), "runtime security options missing")
    require(os.getuid() != 0 and container["Config"]["User"] == f"{os.getuid()}:{os.getgid()}", "runtime must use nonroot caller identity")
    require(container["Config"]["WorkingDir"] == "/opt/codeskeptic", "runtime working directory mismatch")
    tmp = set(host["Tmpfs"]["/tmp"].split(","))
    require(set(host["Tmpfs"]) == {"/tmp"}, "unexpected runtime tmpfs mounts")
    require({"nosuid", "nodev", "noexec"} <= tmp and bool({"size=1g", "size=1073741824"} & tmp), "temporary filesystem is not bounded/restricted")
    binds = [entry for entry in container["Mounts"] if entry["Type"] == "bind"]
    expected = {str(fixture_root): (str(fixture_root), False), "/out": (str(output), True)}
    other_mounts = [entry for entry in container["Mounts"] if entry["Type"] != "bind"]
    require(len(other_mounts) <= 1 and all(entry["Type"] == "tmpfs" and entry["Destination"] == "/tmp" for entry in other_mounts), "unexpected runtime non-bind mounts")
    require(len(binds) == len(expected)
            and {entry["Destination"] for entry in binds} == set(expected), "unexpected runtime mounts")
    for entry in binds:
        source, writable = expected[entry["Destination"]]
        require(entry["Source"] == source and entry["RW"] is writable, "runtime bind identity/permissions mismatch")
    variables = dict(entry.split("=", 1) for entry in container["Config"]["Env"])
    require(set(variables) <= {"PATH", "HOME", "TMPDIR", "LANG", "TERM", "container", "HOSTNAME"}, "unexpected runtime environment")
    require(variables["HOME"] == variables["TMPDIR"] == "/tmp", "runtime temporary home mismatch")


@contextmanager
def created_container(create, case, environment, output):
    cid = None
    try:
        require(run(create, case / "create", environment, output) == 0, "container creation failed")
        cid = identifier((case / "container-id").read_text())
        yield cid
    finally:
        # A create timeout/nonzero exit can still leave a created container.
        # The cidfile belongs to this fresh case directory, never a shared name.
        cidfile = case / "container-id"
        if cid is None and os.path.lexists(cidfile):
            require(cidfile.is_file() and not cidfile.is_symlink() and cidfile.stat().st_size <= 80, "ambiguous owned container ID; inspect retained evidence")
            cid = identifier(cidfile.read_text())
        if cid is not None:
            require(run(["podman", "rm", "--force", cid], case / "cleanup", environment, output) == 0, "owned container cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--base-image", required=True, help="exact cached Linux amd64 image ID, no tags/pulls")
    parser.add_argument("--local-evidence", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(os.getuid() != 0, "run this profile rootless; do not use sudo")
    base = identifier(args.base_image)
    digest = digest_value(args.sha256)
    local = args.local_evidence.resolve(strict=True)
    local_result = json.loads((local / "result.json").read_text())
    require(local_result["schema"] == "codeskeptic-local-action-smoke/v1"
            and local_result["artifact_sha256"] == digest, "local Action measurement/artifact mismatch")
    fixture_root = Path(bind_path(local / "fixtures"))
    output = args.out.absolute()
    output.mkdir()
    environment = child_environment(output)
    # Podman needs the rootless user's runtime/storage configuration. Do not
    # pass it into the container; engine processes never receive scan secrets.
    environment["HOME"] = os.path.expanduser("~")
    if os.environ.get("XDG_RUNTIME_DIR"):
        environment["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
    require(run(["podman", "image", "inspect", base], output / "base-inspect", environment, output) == 0, "cached base image unavailable")
    metadata = json.loads((output / "base-inspect/stdout").read_text())
    require(len(metadata) == 1 and identifier(metadata[0]["Id"]) == base
            and metadata[0]["Os"] == "linux" and metadata[0]["Architecture"] == "amd64", "cached base platform/identity mismatch")
    context = output / "context"
    context.mkdir()
    snapshot = output / "artifact.tar.gz"
    verified_snapshot(args.artifact.absolute(), digest, snapshot)
    package, version = extract_package(snapshot, context, "")
    require(version == local_result["version"], "local/package version mismatch")
    binary_hash = hashlib.sha256((package / "bin/codeskeptic").read_bytes()).hexdigest()
    require(binary_hash == local_result["binary_sha256"], "local/package binary mismatch")
    package.rename(context / "package")
    snapshot.unlink()
    for name in ("Dockerfile", ".dockerignore"):
        shutil.copyfile(ROOT / name, context / name)
    iid = output / "image-id"
    build = ["podman", "build", "--pull=never", "--network=none", "--target", "artifact-runtime",
             "--build-arg", "CODESKEPTIC_RUNTIME_BASE=sha256:" + base, "--iidfile", str(iid),
             "-f", str(context / "Dockerfile"), str(context)]
    require(run(build, output / "build", environment, output) == 0, "offline artifact image build failed")
    image = identifier(iid.read_text())
    require(run(["podman", "image", "inspect", image], output / "image-inspect", environment, output) == 0, "image inspection failed")
    image_metadata = json.loads((output / "image-inspect/stdout").read_text())
    require(len(image_metadata) == 1 and identifier(image_metadata[0]["Id"]) == image
            and image_metadata[0]["Config"]["User"] == "65532:65532", "built image identity/default user mismatch")
    records = []
    for name, source_name, expected, extra in SCENARIOS:
        case = output / name
        case.mkdir()
        reports = case / "reports"
        reports.mkdir()
        source = fixture_root / source_name
        cidfile = case / "container-id"
        create = ["podman", "create", "--pull=never", "--cidfile", str(cidfile),
                  "--userns=keep-id", "--user", f"{os.getuid()}:{os.getgid()}",
                  "--read-only", "--read-only-tmpfs=false", "--image-volume=ignore", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                  "--security-opt=label=disable", "--pids-limit=256", "--cpus=2", "--memory=6g", "--memory-swap=12g",
                  "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=1g,mode=1777", "--env=HOME=/tmp", "--env=TMPDIR=/tmp", "--env=LANG=C.UTF-8",
                  "--mount", f"type=bind,source={fixture_root},destination={fixture_root},ro",
                  "--mount", f"type=bind,source={bind_path(reports)},destination=/out,rw",
                  "--workdir=/opt/codeskeptic", "--entrypoint=/bin/sh", image, "-eu", "-c",
                  'sha256sum /opt/codeskeptic/bin/codeskeptic; /opt/codeskeptic/bin/codeskeptic --version; exec /opt/codeskeptic/bin/codeskeptic "$@"', "--",
                  str(source), "--build-path", str(source), "--lang", "en", *extra, "--sarif", "/out/result.sarif"]
        with created_container(create, case, environment, output) as cid:
            require(run(["podman", "inspect", cid], case / "before", environment, output) == 0, "created container inspection failed")
            before = json.loads((case / "before/stdout").read_text())
            require(len(before) == 1 and identifier(before[0]["Id"]) == cid, "created container ID mismatch")
            validate_runtime(before[0], image, fixture_root, reports)
            code = run(["podman", "start", "--attach", cid], case / "scan", environment, output)
            require(run(["podman", "inspect", cid], case / "after", environment, output) == 0, "terminal container inspection failed")
            after = json.loads((case / "after/stdout").read_text())
            require(len(after) == 1 and identifier(after[0]["Id"]) == cid and after[0]["State"]["Running"] is False
                    and not after[0]["State"]["OOMKilled"] and after[0]["State"]["ExitCode"] == code == expected, "container terminal verdict mismatch")
            validate_runtime(after[0], image, fixture_root, reports)
            require((case / "scan/stdout").read_text() == binary_hash + "  /opt/codeskeptic/bin/codeskeptic\nCodeSkeptic " + version + "\n",
                    "actual container binary hash/version mismatch")
            report = reports / "result.sarif"
            document = json.loads(report.read_text())
            validate(document, code, version)
            require(document == json.loads((local / name / "cli.sarif").read_text())
                    == json.loads((local / name / "action.sarif").read_text()), name + " container/CLI/Action full SARIF mismatch")
            records.append({"scenario": name, "container_id": cid, "exit_code": code,
                            "sarif_sha256": hashlib.sha256(report.read_bytes()).hexdigest(), "full_sarif_equal": True})
    write_json(output / "result.json", {"schema": "codeskeptic-artifact-container-parity/v1", "base_image": base, "image": image,
                                       "artifact_sha256": digest, "binary_sha256": binary_hash, "version": version,
                                       "dockerfile_sha256": hashlib.sha256((context / "Dockerfile").read_bytes()).hexdigest(),
                                       "profile": "rootless-podman-offline-artifact", "hosted_action": False,
                                       "source_rebuild_qualified": False, "scenarios": records})
    print("CONTAINER_PARITY_OK scenarios=6 full_CLI_Action_SARIF_equal=true rootless=true offline=true hosted=false")


if __name__ == "__main__":
    main()
