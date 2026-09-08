#!/usr/bin/env python3
"""Install a checksum-bound trusted Linux artifact for the composite Action.

Local mode never downloads. Release mode only downloads public release assets
from the fixed project repository. Checksums establish integrity, not a signature
or a sandbox: only supply packages whose producer you trust.
"""
import hashlib
import gzip
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

from action_run import ActionError, child_environment, execute, require


VERSION = r"[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*"
TAG = re.compile("v" + VERSION)
PACKAGE = re.compile("codeskeptic-v(" + VERSION + ")-linux-x86_64")
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
REPOSITORY = "github.com/tanzercakir-commits/CodeSkeptic"


def digest_value(text):
    require(re.fullmatch(r"[0-9a-fA-F]{64}", text) is not None, "artifact-sha256 must be exactly 64 hexadecimal characters")
    return text.lower()


def release_version(version, action_ref):
    if version == "latest":
        return version  # Floating acquisition is always an explicit choice.
    selected = version or action_ref
    require(TAG.fullmatch(selected) is not None, "set version to a release tag/latest, or supply a local artifact and checksum; branch/SHA refs do not imply latest")
    return selected


def command_path(name, value):
    require(value and not any(ord(char) < 32 or ord(char) == 127 for char in value), "invalid " + name + " path")
    return Path(value).absolute()


def verified_snapshot(source, digest, destination):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_ARCHIVE, "artifact must be a regular file within 512 MiB")
        actual = hashlib.sha256()
        copied = 0
        with destination.open("xb") as output:
            while block := stream.read(1024 * 1024):
                copied += len(block)
                require(copied <= MAX_ARCHIVE, "artifact exceeded size bound")
                actual.update(block)
                output.write(block)
        require(copied == info.st_size and actual.hexdigest() == digest, "artifact checksum/size mismatch")


def extract_package(archive, destination, selected):
    # tarfile interprets PAX/long-name data before yielding a member. Bound the
    # gzip envelope on disk, then each raw metadata header before that parser
    # can allocate from archive-supplied lengths. The temporary file is owned.
    with tempfile.TemporaryFile(dir=destination) as raw, gzip.open(archive, "rb") as compressed:
        copied = 0
        while block := compressed.read(1024 * 1024):
            copied += len(block)
            require(copied <= MAX_EXPANDED, "decompressed tar exceeds size bound")
            raw.write(block)
        raw.seek(0)
        headers, metadata = 0, 0
        while header := raw.read(512):
            require(len(header) == 512, "truncated tar header")
            if header == b"\0" * 512:
                # Native package padding is zero; no hidden concatenated tar.
                while padding := raw.read(1024 * 1024):
                    require(not padding.strip(b"\0"), "nonzero trailing tar data")
                break
            info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            headers += 1
            require(headers <= 40000 and 0 <= info.size <= MAX_EXPANDED, "raw tar header/size bound exceeded")
            require(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE,
                                 tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME), "unsupported raw tar member")
            if info.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
                metadata += info.size
                require(info.size <= 65536 and metadata <= 8 * 1024 * 1024, "tar metadata exceeds bound")
            skip = (info.size + 511) // 512 * 512
            require(raw.tell() + skip <= copied, "truncated tar member")
            raw.seek(skip, os.SEEK_CUR)
        raw.seek(0)
        return extract_members(raw, destination, selected)


def extract_members(raw, destination, selected):
    # Prevalidate the complete member list before creating extracted files.
    with tarfile.open(fileobj=raw, mode="r:") as package:
        members, names, directories, expanded, root_name = [], set(), set(), 0, None
        for member in package:
            require(len(members) < 20000, "too many archive members")
            name = member.name.removesuffix("/") if member.isdir() else member.name
            require(name and not any(ord(char) < 32 or ord(char) == 127 for char in name), "invalid archive member name")
            parts = name.split("/")
            require("\\" not in name and all(part not in ("", ".", "..") for part in parts), "unsafe archive member path")
            match = PACKAGE.fullmatch(parts[0])
            require(match is not None, "unsupported package root")
            root_name = root_name or parts[0]
            require(parts[0] == root_name and name not in names, "multiple roots or duplicate archive member")
            require(member.isfile() or member.isdir(), "links and special archive members are unsupported")
            require(0 <= member.size <= MAX_EXPANDED, "archive member exceeds size bound")
            expanded += member.size
            require(expanded <= MAX_EXPANDED, "expanded archive exceeds 2 GiB")
            names.add(name)
            if member.isdir():
                require(member.size == 0, "directory member has content")
                directories.add(name)
            members.append((member, name))
        require(root_name is not None, "empty package")
        version = PACKAGE.fullmatch(root_name)[1]
        require(selected in ("", "latest", "v" + version), "release tag/package version mismatch")
        for _, name in members:
            for parent in PurePosixPath(name).parents:
                if str(parent) == ".":
                    break
                require(str(parent) not in names or str(parent) in directories, "file used as archive directory")
        for member, name in members:
            path = destination.joinpath(*name.split("/"))
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as stream, path.open("xb") as output:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
        root = destination / root_name
        binary = root / "bin/codeskeptic"
        require(binary.is_file() and os.access(binary, os.X_OK), "package binary is missing or not executable")
        require((root / "LICENSE").is_file() and (root / "README.md").is_file(), "package license/readme missing")
        require(len(list(root.glob("lib/clang/*/include/stddef.h"))) == 1, "package resource headers missing or ambiguous")
        return root, version


def publish_path(binary_directory):
    path = command_path("GITHUB_PATH", os.environ.get("GITHUB_PATH", ""))
    value = str(binary_directory)
    command_path("installed binary", value)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, "a") as output:
        require(stat.S_ISREG(os.fstat(output.fileno()).st_mode), "GITHUB_PATH must be a regular file")
        output.write(value + "\n")


def acquire(mode):
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"), "this artifact profile requires Linux x86_64")
    require(mode in ("local", "release"), "expected local or release mode")
    local = os.environ.get("INPUT_ARTIFACT_PATH", "")
    checksum = os.environ.get("INPUT_ARTIFACT_SHA256", "")
    version = os.environ.get("INPUT_VERSION", "")
    selected = ""
    if mode == "local":
        source = command_path("artifact", local)
        digest = digest_value(checksum)
        require(not version, "local artifact and release version are mutually exclusive")
    else:
        require(not local and not checksum, "release mode may not ignore local artifact inputs")
        selected = release_version(version, os.environ.get("ACTION_REF", ""))
    runner = command_path("RUNNER_TEMP", os.environ.get("RUNNER_TEMP", ""))
    require(runner.is_dir(), "RUNNER_TEMP is missing")
    # Preflight command-file input before any download or execution.
    command_path("GITHUB_PATH", os.environ.get("GITHUB_PATH", ""))
    installation = Path(tempfile.mkdtemp(prefix="codeskeptic-dist-", dir=runner))
    try:
        if mode == "release":
            download = installation / "download"
            download.mkdir()
            arguments = ["gh", "release", "download"]
            if selected != "latest":
                arguments.append(selected)
            arguments.extend(["-R", REPOSITORY, "-p", "codeskeptic-*-linux-x86_64.tar.gz", "-p", "sha256sums.txt", "-D", str(download)])
            # Pin the public host AND isolate configuration. Ambient GH_HOST,
            # enterprise credentials, stored logins, git config and proxies must
            # not silently select another acquisition origin/credential.
            config = installation / "gh-config"
            config.mkdir(mode=0o700)
            gh_environment = child_environment(installation)
            gh_environment.update(GH_HOST="github.com", GH_CONFIG_DIR=str(config),
                                  GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1",
                                  GIT_TERMINAL_PROMPT="0")
            if os.environ.get("GH_TOKEN"):
                gh_environment["GH_TOKEN"] = os.environ["GH_TOKEN"]
            # gh alone receives the explicit acquisition token, never the analyzer.
            download_code, _, _ = execute(arguments, gh_environment, 120)
            require(download_code == 0, "release download failed")
            archives = list(download.glob("codeskeptic-*-linux-x86_64.tar.gz"))
            require(len(archives) == 1, "release must contain exactly one Linux x86_64 archive")
            source = archives[0]
            sums = download / "sha256sums.txt"
            require(sums.is_file() and not sums.is_symlink() and sums.stat().st_size <= 1024 * 1024, "missing or oversized release checksums")
            matches = []
            for line in sums.read_text().splitlines():
                match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
                if match and match[2] == source.name:
                    matches.append(match[1])
            require(len(matches) == 1, "missing or ambiguous asset checksum")
            digest = digest_value(matches[0])
        snapshot = installation / "artifact.tar.gz"
        verified_snapshot(source, digest, snapshot)
        root, actual_version = extract_package(snapshot, installation, selected)
        environment = child_environment(installation)
        _, identity, _ = execute([str(root / "bin/codeskeptic"), "--version"], environment, 15, capture=True)
        require(identity.strip() == "CodeSkeptic " + actual_version, "installed binary/package identity mismatch")
        snapshot.unlink()  # owned verified snapshot only; keep the installed tree.
        publish_path(root / "bin")
        print("Installed CodeSkeptic " + actual_version + " (sha256 " + digest + ")")
        return root
    except BaseException:
        shutil.rmtree(installation)  # only this invocation's freshly created directory
        raise


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2, "expected one acquisition mode")
        acquire(sys.argv[1])
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        print("::error::CodeSkeptic acquisition failed: " + str(error), file=sys.stderr)
        sys.exit(2)
