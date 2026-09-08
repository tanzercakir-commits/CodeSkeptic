#!/usr/bin/env python3
"""Candidate-only native Windows/macOS artifact first scans with retained evidence.

Trusted local build archives only. This is a bounded test harness, not an OS
sandbox, installer, signing tool, release publisher or independent attestation.
The caller hides/restores its known LLVM installation; this helper never does.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile


REPO = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_REPORT = 2 * 1024 * 1024
MAX_MEMBERS = 20000
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?")
DEVELOPER_ENV = re.compile(r"INCLUDE|EXTERNAL_INCLUDE|LIB|LIBPATH|DevEnvDir|VSINSTALLDIR|VCINSTALLDIR|VCIDEInstallDir|VCToolsInstallDir|VCToolsVersion|VCToolsRedistDir|WindowsSdkDir|WindowsSDKVersion|WindowsSdkBinPath|WindowsSDKBinVersion|WindowsSDKLibVersion|UniversalCRTSdkDir|UCRTVersion|VSCMD_.*|Framework.*|ExtensionSdkDir", re.I)
WINDOWS_OS_LOCATORS = ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemDrive")
# One retained failed native build, not a configurable external executable.
SDK_ARTIFACT_SHA256 = "644407b4102be943aba0e2ccfed99302e42a858b20671de32b182e418028095f"
SDK_PACKAGE_SHA256 = "261d97c1632afec144b6845b2d24809710866d0356847d0aba51445a77ed1df9"
SDK_SOURCE = "b459d99feddd8e94a4252312ca03dc247500bbf9"
SDK_VERSION = "0.4.9-dev+gb459d99feddd"
SDK_ROOT = "codeskeptic-v" + SDK_VERSION + "-windows-x86_64"
SDK_PACKAGE_MEMBER = "codeskeptic-platform/" + SDK_ROOT + ".zip"
SDK_FIXTURE_MEMBER = "codeskeptic-platform/fixtures/c-finding/güvenli_çalışma.c"
SDK_DATABASE_MEMBER = "codeskeptic-platform/fixtures/c-finding/compile_commands.json"


class QualificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise QualificationError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data):
    with Path(path).open("xb") as output:
        output.write(data)


def read_regular(path, limit=MAX_REPORT):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "nonempty bounded regular file required")
    with path.open("rb") as stream:
        current = os.fstat(stream.fileno())
        require((current.st_dev, current.st_ino, current.st_size) == (info.st_dev, info.st_ino, info.st_size), "input changed while opening")
        data = stream.read(limit + 1)
    require(len(data) == info.st_size, "input changed or exceeds bound")
    return data


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    def invalid(_):
        raise QualificationError("non-finite JSON")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def git(*args):
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(REPO), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    require(result.returncode == 0 and len(result.stdout) <= MAX_REPORT, "source Git check failed")
    return result.stdout


def identity(source, version):
    require(isinstance(source, str) and SHA.fullmatch(source), "full source SHA required")
    require(isinstance(version, str) and VERSION.fullmatch(version), "complete version required")
    require(git("rev-parse", "HEAD").decode().strip() == source and not git("status", "--porcelain").strip(),
            "exact clean source checkout required")
    cmake = git("show", source + ":CMakeLists.txt")
    bases = re.findall(rb"(?m)^project\(CodeSkeptic VERSION ([0-9]+)\.([0-9]+)\.([0-9]+) LANGUAGES C CXX\)$", cmake)
    require(len(bases) == 1, "authored version missing")
    major, minor, patch = map(int, bases[0])
    short = git("rev-parse", "--short=12", source).decode().strip()
    require(version == f"{major}.{minor}.{patch + 1}-dev+g{short}", "candidate/source version mismatch")
    return {"sha": source, "cmake_sha256": sha(cmake), "version": version,
            "helper_sha256": sha(git("show", source + ":scripts/platform_first_scan.py")),
            "workflow_sha256": sha(git("show", source + ":.github/workflows/release.yml"))}


def runner_profile():
    system, machine = platform.system(), platform.machine()
    if system == "Windows" and machine.lower() in ("amd64", "x86_64"):
        target = "windows-x86_64"
    elif system == "Darwin" and machine == "arm64":
        target = "darwin-arm64"
    else:
        raise QualificationError("requires actual native Windows x86_64 or macOS arm64 runner")
    return {"target": target, "system": system, "machine": machine, "release": platform.release(),
            "os_version": platform.version(), "python": platform.python_version(),
            "runner_os": os.environ.get("RUNNER_OS", "not-recorded"),
            "runner_arch": os.environ.get("RUNNER_ARCH", "not-recorded"),
            "runner_image": os.environ.get("ImageVersion", "not-recorded")}


def snapshot(archive, digest, destination):
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "archive SHA-256 required")
    info = archive.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_ARCHIVE, "bounded regular archive required")
    with archive.open("rb") as source, destination.open("xb") as output:
        opened = os.fstat(source.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, info.st_size), "archive changed while opening")
        copied, h = 0, hashlib.sha256()
        for block in iter(lambda: source.read(1024 * 1024), b""):
            copied += len(block)
            require(copied <= MAX_ARCHIVE, "archive grew beyond bound")
            output.write(block); h.update(block)
    require(copied == info.st_size and h.hexdigest() == digest, "archive checksum mismatch")


def member_path(name, root, seen):
    require(isinstance(name, str) and name and len(name) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in name), "invalid archive path")
    parts = name.split("/")
    require("\\" not in name and ":" not in name and parts[0] == root
            and all(part not in ("", ".", "..") and not part.endswith((".", " ")) for part in parts), "unsafe archive path")
    # Reject case collisions and Windows special device names on both platforms.
    for part in parts:
        require(not re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?", part, re.I), "reserved archive path")
    require(name.casefold() not in seen, "duplicate/case-colliding archive member")
    seen.add(name.casefold())
    return parts


def extract(archive, destination, root_name):
    """Bound raw metadata before parser allocation; no archive extractall."""
    records, seen, directories, total = [], set(), set(), 0
    with tempfile.TemporaryFile() as raw:
        if archive.name.endswith(".tar.gz"):
            with gzip.open(archive, "rb") as compressed:
                expanded = 0
                for block in iter(lambda: compressed.read(1024 * 1024), b""):
                    expanded += len(block)
                    require(expanded <= MAX_EXPANDED, "expanded tar bound exceeded")
                    raw.write(block)
            raw.seek(0)
            headers = metadata = 0
            while header := raw.read(512):
                require(len(header) == 512, "truncated tar header")
                if header == b"\0" * 512:
                    break
                info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                headers += 1
                require(headers <= 2 * MAX_MEMBERS and 0 <= info.size <= MAX_EXPANDED, "tar header bound exceeded")
                require(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE,
                                     tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME), "unsupported tar member")
                if info.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
                    metadata += info.size
                    require(info.size <= 65536 and metadata <= 8 * 1024 * 1024, "tar metadata bound exceeded")
                end = raw.tell() + (info.size + 511) // 512 * 512
                require(end <= expanded, "truncated tar data")
                raw.seek(end)
            raw.seek(0)
            package = tarfile.open(fileobj=raw, mode="r:")
            iterator = package
        else:
            # The complete ZIP is itself capped before the central directory is
            # parsed. Trusted packagers do not emit encrypted/ZIP64 giant archives.
            require(archive.stat().st_size <= MAX_ARCHIVE, "zip bound exceeded")
            package = zipfile.ZipFile(archive)
            iterator = package.infolist()
        with package:
            for item in iterator:
                require(len(records) < MAX_MEMBERS, "member count exceeded")
                if isinstance(item, tarfile.TarInfo):
                    require(item.isfile() or item.isdir(), "links/special members forbidden")
                    directory, size, mode = item.isdir(), item.size, item.mode
                    name = item.name.removesuffix("/") if directory else item.name
                else:
                    mode = item.external_attr >> 16
                    require(not item.flag_bits & 1 and (not stat.S_IFMT(mode) or stat.S_ISREG(mode) or stat.S_ISDIR(mode)), "encrypted/link/special ZIP member forbidden")
                    directory, size = item.is_dir(), item.file_size
                    name = item.filename.removesuffix("/") if directory else item.filename
                parts = member_path(name, root_name, seen)
                require(0 <= size <= MAX_EXPANDED and (not directory or size == 0), "invalid member size")
                total += size
                require(total <= MAX_EXPANDED, "member bytes exceeded")
                if directory:
                    directories.add(name.casefold())
                records.append((item, parts, directory, size, mode))
            require(records, "empty archive")
            for _, parts, _, _, _ in records:
                for count in range(1, len(parts)):
                    parent = "/".join(parts[:count]).casefold()
                    require(parent not in seen or parent in directories, "archive file/directory conflict")
            for item, parts, directory, size, mode in records:
                path = destination.joinpath(*parts)
                if directory:
                    path.mkdir(parents=True, exist_ok=True)
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                stream = package.extractfile(item) if isinstance(item, tarfile.TarInfo) else package.open(item)
                with stream, path.open("xb") as output:
                    copied = 0
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        copied += len(block)
                        require(copied <= size, "member grew beyond declared size")
                        output.write(block)
                    require(copied == size, "truncated member")
                if os.name != "nt":
                    path.chmod(0o755 if mode & 0o111 else 0o644)
    return destination / root_name


def child_environment(home, temporary):
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS"}}
    environment.update(HOME=str(home), USERPROFILE=str(home), TEMP=str(temporary), TMP=str(temporary),
                       TMPDIR=str(temporary), LANG="en_US.UTF-8", LC_ALL="en_US.UTF-8")
    if os.name == "nt":
        root = environment.get("SystemRoot", environment.get("SYSTEMROOT", "C:\\Windows"))
        environment["PATH"] = str(Path(root) / "System32") + os.pathsep + root
    else:
        environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    require(not any(DEVELOPER_ENV.fullmatch(k) for k in environment), "developer environment leaked")
    return environment


def windows_locator_environment(base):
    """Explicit OS-locator profile; never forward PATH or developer overrides."""
    environment = dict(base)
    for name in WINDOWS_OS_LOCATORS:
        values = [v for k, v in os.environ.items() if k.casefold() == name.casefold()]
        require(len(values) == 1 and 0 < len(values[0]) <= 4096
                and not any(ord(c) < 32 for c in values[0]), "missing/ambiguous OS locator: " + name)
        require(not any(k.casefold() == name.casefold() for k in base), "OS locator already in baseline")
        environment[name] = values[0]
    return environment


def sdk_inputs(archive, output):
    """Select three exact members only, after verifying the complete historical ZIP."""
    outer = output / "historical-artifact.zip"
    snapshot(archive, SDK_ARTIFACT_SHA256, outer)
    selected, seen, total = {}, set(), 0
    with zipfile.ZipFile(outer) as package:
        require(len(package.infolist()) <= MAX_MEMBERS, "diagnostic member count exceeded")
        for item in package.infolist():
            name = item.filename.removesuffix("/") if item.is_dir() else item.filename
            member_path(name, name.split("/")[0], seen)
            mode = item.external_attr >> 16
            require(not item.flag_bits & 1 and (not stat.S_IFMT(mode) or stat.S_ISREG(mode) or stat.S_ISDIR(mode)),
                    "diagnostic encrypted/link/special member")
            total += item.file_size
            require(0 <= item.file_size <= MAX_EXPANDED and total <= MAX_EXPANDED, "diagnostic expanded bound exceeded")
            if name in (SDK_PACKAGE_MEMBER, SDK_FIXTURE_MEMBER, SDK_DATABASE_MEMBER):
                limit = MAX_ARCHIVE if name == SDK_PACKAGE_MEMBER else MAX_REPORT
                require(not item.is_dir() and 0 < item.file_size <= limit, "invalid diagnostic input")
                with package.open(item) as stream:
                    data = stream.read(limit + 1)
                require(len(data) == item.file_size, "diagnostic input size mismatch")
                selected[name] = data
    require(set(selected) == {SDK_PACKAGE_MEMBER, SDK_FIXTURE_MEMBER, SDK_DATABASE_MEMBER}, "exact diagnostic members missing")
    require(sha(selected[SDK_PACKAGE_MEMBER]) == SDK_PACKAGE_SHA256, "historical package checksum mismatch")
    nested = output / (SDK_ROOT + ".zip")
    write_new(nested, selected[SDK_PACKAGE_MEMBER])
    return nested, selected[SDK_FIXTURE_MEMBER], selected[SDK_DATABASE_MEMBER]


def sdk_arms(binary, source, database, cwd, base, output, version):
    restored = windows_locator_environment(base)
    inputs = {str(p): file_hash(p) for p in (binary, source, database)}
    arms = []
    for label, env in (("baseline", base), ("os-locators", restored)):
        report_path = output / (label + "-report.json")
        arm = {"name": label, "valid_report": False, "execution": None}
        try:
            arm["execution"] = execute([str(binary), str(source), "--build-path", str(database.parent),
                                        "--lang", "en", "--json", str(report_path)], cwd, env, output, label)
            code = arm["execution"]["exit_code"]
            require(code in (1, 2), "diagnostic finding input has unexpected exit")
            arm["verdict"] = validate_report(parse_json(read_regular(report_path)), version, code, "c", source)
            arm["report_sha256"] = file_hash(report_path)
            arm["stdio_header_missing"] = b"'stdio.h' file not found" in read_regular(output / (label + ".stderr")) if code == 2 else False
            arm["valid_report"] = True
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            arm["error"] = str(error)
        arms.append(arm)
        require({p: file_hash(Path(p)) for p in inputs} == inputs, "diagnostic inputs changed between arms")
    return arms


def sdk_diagnostic(args):
    """Native A/B on a pinned OLD binary; never a qualification of current HEAD."""
    info = identity(args.source_sha, args.version)
    require(read_regular(Path(__file__)) == git("show", args.source_sha + ":scripts/platform_first_scan.py"), "helper differs from source")
    runner = runner_profile()
    require(runner["system"] == "Windows", "SDK diagnostic requires native Windows")
    require(args.archive_sha256 == SDK_ARTIFACT_SHA256, "only pinned historical diagnostic artifact allowed")
    require_hidden_llvm(args)
    require(os.environ.get("GITHUB_SHA") == args.source_sha, "diagnostic hosted event/source mismatch")
    require(not os.path.lexists(args.output), "output exists; use fresh diagnostic directory")
    args.output.mkdir()
    try:
        archive, fixture_bytes, original_database_bytes = sdk_inputs(args.archive, args.output)
        original_database = parse_json(original_database_bytes)
        require(isinstance(original_database, list) and len(original_database) == 1
                and isinstance(original_database[0], dict), "historical database shape mismatch")
        original = original_database[0]
        require(set(original) == {"directory", "file", "arguments"}
                and isinstance(original["directory"], str) and isinstance(original["file"], str)
                and original["arguments"] == ["clang", "-std=c11", "-c", original["file"]], "historical command semantics changed")
        write_new(args.output / "historical-compile_commands.json", original_database_bytes)
        source = args.output / "güvenli_çalışma.c"
        database = args.output / "compile_commands.json"
        write_new(source, fixture_bytes)
        # Same archived source bytes and original command semantics, rebased once
        # to this runner's fresh path; no SDK/include flags in either arm.
        write_new(database, canonical([{"directory": str(args.output), "file": str(source),
                                       "arguments": ["clang", "-std=c11", "-c", str(source)]}]))
        with tempfile.TemporaryDirectory(prefix="codeskeptic SDK comparison ") as temporary:
            cwd = Path(temporary)
            package = extract(archive, cwd, SDK_ROOT)
            binary = package / "bin/codeskeptic.exe"
            binary_digest = sha(read_regular(binary, MAX_ARCHIVE))
            home, temp = cwd / "home", cwd / "temporary"
            home.mkdir(); temp.mkdir()
            base = child_environment(home, temp)
            version = execute([str(binary), "--version"], cwd, base, args.output, "version", 15)
            require(version["exit_code"] == 0 and (args.output / "version.stdout").read_text().strip() == "CodeSkeptic " + SDK_VERSION,
                    "historical executable version mismatch")
            arms = sdk_arms(binary, source, database, cwd, base, args.output, SDK_VERSION)
            require(file_hash(binary) == binary_digest and file_hash(archive) == SDK_PACKAGE_SHA256,
                    "historical artifact changed during diagnostic")
        result = {"schema": "codeskeptic-windows-sdk-diagnostic/v1", "purpose": "historical binary environment A/B; not qualification",
                  "diagnostic_source": info, "binary_source": SDK_SOURCE, "binary_version": SDK_VERSION,
                  "runner": runner, "historical_run_id": "34217016638", "historical_artifact_id": "10052976442",
                  "artifact_sha256": SDK_ARTIFACT_SHA256, "package_sha256": SDK_PACKAGE_SHA256,
                  "binary_sha256": binary_digest, "fixture_sha256": file_hash(source), "database_sha256": file_hash(database),
                  "historical_database_sha256": sha(original_database_bytes),
                  "added_os_locators": {k: v for k, v in windows_locator_environment({}).items()},
                  "baseline_environment_keys": sorted(base), "child_path": base["PATH"],
                  "baseline_environment_sha256": sha(canonical(base)),
                  "os_locators_environment_sha256": sha(canonical(windows_locator_environment(base))),
                  "llvm_original": str(args.llvm_original), "llvm_hidden": str(args.llvm_hidden), "arms": arms,
                  "baseline_failure_then_locator_finding": all(a["valid_report"] for a in arms)
                      and [a["execution"]["exit_code"] for a in arms] == [2, 1]
                      and arms[0].get("stdio_header_missing") is True}
        require(identity(args.source_sha, args.version) == info, "diagnostic source changed")
        write_new(args.output / "sdk-diagnostic.json", canonical(result))
        require(result["baseline_failure_then_locator_finding"], "OS-locator hypothesis not established; no qualification fallback")
        print("SDK_DIAGNOSTIC_OBSERVED baseline=2 os-locators=1 historical-source=" + SDK_SOURCE)
        return result
    except BaseException as error:
        write_new(args.output / "diagnostic-failure.json", canonical({"diagnostic_source_sha": args.source_sha,
                  "binary_source": SDK_SOURCE, "error": str(error), "purpose": "diagnostic; not qualification"}))
        raise


def require_hidden_llvm(args):
    require(args.llvm_original.is_absolute() and args.llvm_hidden.is_absolute()
            and args.llvm_original != args.llvm_hidden and not os.path.lexists(args.llvm_original)
            and args.llvm_hidden.is_dir() and not args.llvm_hidden.is_symlink(), "known LLVM installation must be hidden by caller")


def execute(argv, cwd, environment, output, label, timeout=60):
    result = {"argv": [str(a) for a in argv], "cwd": str(cwd), "timeout_seconds": timeout,
              "exit_code": None, "timed_out": False}
    stdout, stderr = output / (label + ".stdout"), output / (label + ".stderr")
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            try:
                completed = subprocess.run(argv, cwd=cwd, env=environment, stdout=out, stderr=err, timeout=timeout)
                result["exit_code"] = completed.returncode
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
    finally:
        write_new(output / (label + ".command.json"), canonical(result))
    require(not result["timed_out"], "native command timed out")
    require(stdout.stat().st_size <= MAX_REPORT and stderr.stat().st_size <= MAX_REPORT, "native output exceeds bound")
    result.update(stdout_sha256=file_hash(stdout), stderr_sha256=file_hash(stderr))
    return result


def validate_report(report, version, expected, language, source):
    require(isinstance(report, dict) and report.get("schema") == "codeskeptic-report/v1"
            and report.get("tool") == "CodeSkeptic" and report.get("tool_version") == version,
            "native report identity mismatch")
    require(type(report.get("exit_code")) is int and report["exit_code"] == expected
            and report.get("complete") is (expected != 2)
            and report.get("status") == {0: "clean", 1: "findings", 2: "failed"}[expected], "native report verdict mismatch")
    evidence = report.get("evidence")
    expected_flags = {"no_inputs", "no_rules", "tool_failed", "summary_load_failed", "summary_stale",
                      "summary_save_failed", "baseline_load_failed", "baseline_write_failed", "baseline_recorded", "report_write_failed"}
    require(isinstance(evidence, dict) and set(evidence) == expected_flags
            and all(type(v) is bool for v in evidence.values()) and not any(evidence.values()),
            "native command evidence inconsistent with the fixed first-scan profile")
    coverage = report.get("coverage")
    require(isinstance(coverage, dict) and coverage.get("schema") == "codeskeptic-source-coverage/v1",
            "native coverage missing")
    analyzed, skipped = (0, 1) if expected == 2 else (1, 0)
    expected_counts = {"attempted_tus": 1, "analyzed_tus": analyzed, "broken_tus": skipped,
                       "skipped_tus": skipped, "failed_tus": 0, "recovery_tus": 0,
                       "attempted_commands": 1, "analyzed_commands": analyzed,
                       "skipped_commands": skipped, "failed_commands": 0, "incomplete_functions": 0}
    require(all(type(coverage.get(key)) is int and coverage[key] == value
                for key, value in expected_counts.items()), "native coverage counters mismatch")
    require(coverage.get("complete") is (expected != 2)
            and coverage.get("accept_partial_coverage") is False
            and coverage.get("analyze_broken_tus") is False, "native coverage acceptance mismatch")
    expected_source = Path(source).resolve()
    def same_source(value):
        return isinstance(value, str) and Path(value).is_absolute() and Path(value).resolve() == expected_source
    sources = coverage.get("sources")
    require(isinstance(sources, list) and len(sources) == 1 and isinstance(sources[0], dict), "one native source row required")
    row = sources[0]
    require(same_source(row.get("file")) and row.get("status") == ("skipped" if skipped else "analyzed")
            and row.get("reason") == ("broken_translation_unit" if skipped else "analyzed"), "native source identity/status mismatch")
    command_counts = {"commands": 1, "analyzed_commands": analyzed, "skipped_commands": skipped,
                      "failed_commands": 0, "recovery_commands": 0}
    require(all(type(row.get(key)) is int and row[key] == value for key, value in command_counts.items()),
            "native source commands mismatch")
    prepass = row.get("prepass")
    require(isinstance(prepass, dict) and prepass.get("status") == "not_requested"
            and prepass.get("reason") == "" and type(prepass.get("recovery_commands")) is int
            and prepass["recovery_commands"] == 0, "unexpected native prepass/recovery")
    counts = report.get("finding_counts")
    diagnostics = report.get("diagnostics")
    require(isinstance(counts, dict) and isinstance(diagnostics, list)
            and set(counts) == {"total", "blocking", "report_only"}
            and all(type(v) is int and v >= 0 for v in counts.values())
            and type(report.get("total")) is int and report["total"] == len(diagnostics)
            and counts["total"] == len(diagnostics)
            and counts["blocking"] + counts["report_only"] == counts["total"], "native finding counts mismatch")
    require(all(isinstance(d, dict) and type(d.get("blocks_verdict")) is bool and same_source(d.get("file"))
                for d in diagnostics), "native diagnostic source/blocking evidence mismatch")
    require(sum(d["blocks_verdict"] for d in diagnostics) == counts["blocking"], "native blocking counts mismatch")
    if expected == 1:
        require(counts["blocking"] >= 1 and any(d.get("rule_id") == "null-deref" and d["blocks_verdict"]
                and d.get("capability_tier") == "supported" for d in diagnostics), "supported native finding missing")
    else:
        require(not diagnostics and counts.get("blocking") == 0 and counts.get("report_only") == 0, "unexpected native findings")
    return {"language": language, "exit_code": expected, "complete": expected != 2,
            "findings": len(diagnostics), "coverage": coverage}


def qualify(args):
    info = identity(args.source_sha, args.version)
    require(read_regular(Path(__file__)) == git("show", args.source_sha + ":scripts/platform_first_scan.py"), "helper differs from source")
    runner = runner_profile()
    require_hidden_llvm(args)
    require(isinstance(args.source_binary_sha256, str) and DIGEST.fullmatch(args.source_binary_sha256), "source binary SHA-256 required")
    os_locators = getattr(args, "windows_os_locators", False)
    require(not os_locators or runner["system"] == "Windows", "OS-locator profile is Windows-only")
    root_name = "codeskeptic-v" + args.version + "-" + runner["target"]
    extension = ".zip" if runner["system"] == "Windows" else ".tar.gz"
    require(args.archive.name == root_name + extension, "archive filename/source/platform mismatch")
    require(not os.path.lexists(args.output), "output exists; use fresh evidence directory")
    args.output.mkdir()
    try:
        event = {name: os.environ.get(name, "not-recorded") for name in
                 ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")}
        require(event["GITHUB_SHA"] == args.source_sha, "hosted event/source mismatch")
        archive = args.output / args.archive.name
        snapshot(args.archive, args.archive_sha256, archive)
        write_new(args.output / "source-runner.json", canonical({"source": info, "runner": runner, "event": event}))
        scans, fixtures = args.output / "scans", args.output / "fixtures"
        scans.mkdir(); fixtures.mkdir()
        with tempfile.TemporaryDirectory(prefix="codeskeptic package extraction ") as temporary:
            extraction = Path(temporary)
            package = extract(archive, extraction, root_name)
            binary = package / "bin" / ("codeskeptic.exe" if runner["system"] == "Windows" else "codeskeptic")
            require(binary.is_file() and not binary.is_symlink(), "packaged executable missing")
            require((package / "LICENSE").is_file() and (package / "README.md").is_file()
                    and (package / "DEPENDENCIES.txt").is_file(), "package metadata missing")
            headers = list(package.glob("lib/clang/*/include/stddef.h"))
            require(len(headers) == 1, "packaged intrinsic headers missing or ambiguous")
            require(headers[0].parent.parent.name == "20", "candidate profile requires LLVM resource major 20")
            binary_hash = file_hash(binary)
            if runner["system"] == "Windows":
                require(binary_hash == args.source_binary_sha256, "Windows packaged/source binary mismatch")
            home, temp = extraction / "home", extraction / "temporary"
            home.mkdir(); temp.mkdir()
            env = child_environment(home, temp)
            if os_locators:
                env = windows_locator_environment(env)
            version_result = execute([str(binary), "--version"], extraction, env, scans, "version", 15)
            require(version_result["exit_code"] == 0 and (scans / "version.stdout").read_text().strip() == "CodeSkeptic " + args.version,
                    "packaged native version mismatch")
            caps_result = execute([str(binary), "--capabilities", "--json"], extraction, env, scans, "capabilities", 15)
            require(caps_result["exit_code"] == 0, "capabilities command failed")
            caps = parse_json(read_regular(scans / "capabilities.stdout"))
            require(isinstance(caps, dict) and caps.get("product") == "CodeSkeptic" and caps.get("version") == args.version
                    and type(caps.get("schema_version")) is int and caps["schema_version"] == 2, "capabilities identity mismatch")
            macro = "_WIN32" if runner["system"] == "Windows" else "__APPLE__"
            cases = []
            for language, suffix, standard in (("c", ".c", "c11"), ("cpp", ".cpp", "c++17")):
                for scenario, expected in (("clean", 0), ("finding", 1), ("unavailable", 2)):
                    label = language + "-" + scenario
                    fixture = fixtures / label
                    fixture.mkdir()
                    source = fixture / ("güvenli_çalışma" + suffix)
                    header = "stddef.h" if language == "c" else "cstddef"
                    body = (f"#if !defined({macro})\n#error incorrect_native_platform\n#endif\n#include <{header}>\n")
                    if scenario == "clean":
                        body += "int value(void) { return 42; }\n"
                    elif scenario == "finding":
                        body += "#include <stdio.h>\nint value(void) { int *p = 0; return *p; }\n"
                    else:
                        body += '#include "codeskeptic_qualification_missing_header.h"\nint value(void) { return 42; }\n'
                    write_new(source, body.encode())
                    database = fixture / "compile_commands.json"
                    write_new(database, canonical([{"directory": str(fixture), "file": str(source),
                                                    "arguments": ["clang" if language == "c" else "clang++", "-std=" + standard, "-c", str(source)]}]))
                    report_path = scans / (label + "-rapor-ç.json")
                    execution = execute([str(binary), str(source), "--build-path", str(fixture), "--lang", "en", "--json", str(report_path)], extraction, env, scans, label)
                    require(execution["exit_code"] == expected, "first-scan exit mismatch: " + label)
                    report = validate_report(parse_json(read_regular(report_path)), args.version, expected, language, source)
                    cases.append({"name": label, "input_sha256": file_hash(source), "database_sha256": file_hash(database),
                                  "report_sha256": file_hash(report_path), "execution": execution, "verdict": report})
            dependency_bytes = read_regular(package / "DEPENDENCIES.txt")
            write_new(args.output / "DEPENDENCIES.txt", dependency_bytes)
            require(file_hash(binary) == binary_hash and file_hash(archive) == args.archive_sha256,
                    "artifact changed during qualification")
        require(identity(args.source_sha, args.version) == info, "source changed during qualification")
        result = {"schema": "codeskeptic-platform-first-scan/v1", "source": info, "runner": runner, "event": event,
                  "artifact": {"name": archive.name, "sha256": args.archive_sha256, "size": archive.stat().st_size,
                               "binary_sha256": binary_hash, "source_binary_sha256": args.source_binary_sha256,
                               "resource_major": headers[0].parent.parent.name, "version": args.version},
                  "profile": {"llvm_original": str(args.llvm_original), "llvm_hidden": str(args.llvm_hidden),
                              "developer_environment": "excluded from native children", "native_installation_hidden": True,
                              "windows_os_locators": {k: env[k] for k in WINDOWS_OS_LOCATORS} if os_locators else {},
                              "sdk": "host-provided Windows SDK/MSVC or Apple CLT; not a toolchain-free OS",
                              "network": "hosted setup may download toolchain; helper makes no network calls",
                              "signing": "no publisher signing/notarization claim; macOS may have local ad-hoc signature",
                              "scope": "C/C++ UTF-8 explicit-input clean/finding/unavailable first scans; not full cross-platform parity or hosted final-job success"},
                  "cases": cases, "result": "PASS"}
        write_new(args.output / "result.json", canonical(result))
        print("PLATFORM_FIRST_SCAN_OK target=" + runner["target"] + " source=" + args.source_sha + " cases=6")
        return result
    except BaseException as error:
        write_new(args.output / "failure.json", canonical({"source_sha": args.source_sha, "result": "FAIL", "error": str(error)}))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-binary-sha256")
    parser.add_argument("--sdk-diagnostic", action="store_true")
    parser.add_argument("--windows-os-locators", action="store_true")
    parser.add_argument("--llvm-original", type=Path, required=True)
    parser.add_argument("--llvm-hidden", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not (args.sdk_diagnostic and args.windows_os_locators), "diagnostic controls both environment arms itself")
        if args.sdk_diagnostic:
            sdk_diagnostic(args)
        else:
            qualify(args)
    except (OSError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        label = "SDK_DIAGNOSTIC_FAIL " if args.sdk_diagnostic else "PLATFORM_FIRST_SCAN_FAIL "
        parser.exit(1, label + str(error) + "\n")


if __name__ == "__main__":
    main()
